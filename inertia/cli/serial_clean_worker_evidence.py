# cython: language_level=3, infer_types=True
"""Transport typed project evidence into isolated clean workers.

Layer: CLI/fallback/reporting.
Responsibility: encode, validate, and attach already-derived caller-use and
Widening artifacts across the parent-to-worker JSON boundary. No semantic fact
is inferred, rebuilt, or reclassified here.
"""

from __future__ import annotations
import typing
import cython

import json
import os
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from inertia.lowering.callee_callsite_codec import (
    callee_callsite_census_map_from_record_8616,
    callee_callsite_census_map_record_8616,
)
from inertia.lowering.callee_callsite_contracts import (
    CalleeCallsiteCensus8616,
    attach_callee_callsite_censuses_8616,
)
from inertia.lowering.callee_global_object_sources import (
    GlobalObjectSourceEvidence8616,
    attach_project_global_object_source_evidence_8616,
    project_global_object_source_evidence_8616,
)
from inertia.lowering.callee_pointer_codec import (
    callee_pointer_argument_evidence_map_from_record_8616,
    callee_pointer_argument_evidence_map_record_8616,
)
from inertia.lowering.callee_pointer_contracts import (
    CalleePointerArgumentEvidence8616,
    callee_pointer_argument_evidence_by_addr_8616,
    record_callee_pointer_argument_evidence_8616,
)
from inertia.lowering.global_object_source_codec import (
    global_object_source_evidence_from_record_8616,
    global_object_source_evidence_record_8616,
)
from inertia.lowering.scalar_interface_transport import (
    ScalarInterface8616,
    attach_scalar_interface_8616,
    scalar_interface_from_record_8616,
    scalar_interface_records_8616,
)
from inertia.semantics.callsite_summary import (
    CallerReturnUseEvidence8616,
    caller_return_use_evidence_by_addr_8616,
    record_caller_return_use_evidence_8616,
)
from inertia.semantics.callsite_summary_program import (
    ProgramCallsiteSummaryEvidence8616,
    attach_program_callsite_summary_evidence_8616,
    program_callsite_summary_evidence_8616,
)
from inertia.semantics.callsite_summary_program_codec import (
    program_callsite_summary_evidence_from_record_8616,
    program_callsite_summary_evidence_record_8616,
)
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

from .cache import DECOMPILATION_CACHE_SOURCE_FILES, _cache_source_digest
from .discovery_cache_contract import (
    caller_return_use_evidence_from_record_8616,
    caller_return_use_evidence_record_8616,
)
from .project_evidence_transport import (
    attach_project_bounded_global_object_ranges_8616,
    attach_project_global_object_layout_evidence_8616,
    project_bounded_global_object_ranges_8616,
    project_global_object_layout_evidence_8616,
)
import dataclasses
import operator
import builtins

_SERIAL_CLEAN_WORKER_EVIDENCE_ENV_8616 = "INERTIA_SERIAL_CLEAN_WORKER_EVIDENCE"
_SERIAL_CLEAN_WORKER_EVIDENCE_SCHEMA_8616 = 9
_SERIAL_CLEAN_WORKER_DECODE_OWNER_8616 = SimpleNamespace()


@dataclasses.dataclass(frozen=True, )
class _SerialCleanWorkerEvidence8616:
    """Typed evidence decoded from one parent-to-worker payload."""

    caller_return_use_by_addr: object
    global_object_layout: GlobalObjectLayoutEvidence8616 | None
    bounded_global_ranges: ProjectBoundedGlobalObjectRangeEvidence8616 | None
    callee_pointer_by_addr: object
    global_object_sources: GlobalObjectSourceEvidence8616 | None
    callee_callsites_by_addr: object
    program_callsite_summaries: ProgramCallsiteSummaryEvidence8616 | None
    scalar_interfaces: object


@cython.ccall
def _widening_payload_8616(source_project: object) -> tuple[object, object]:
    """Return coherent serialized layout and range records when available."""
    layouts: object
    ranges: object
    layouts = project_global_object_layout_evidence_8616(source_project)
    ranges = project_bounded_global_object_ranges_8616(source_project)
    if ranges is not None and layouts is None:
        raise ValueError("clean-worker bounded ranges have no layout dependency")
    if ranges is not None and layouts is not None and operator.ne(ranges.layouts, layouts):
        raise ValueError("clean-worker bounded ranges disagree with project layouts")
    return (
        None if layouts is None else global_object_layout_evidence_record_8616(layouts),
        None if ranges is None else project_bounded_global_ranges_record_8616(ranges),
    )


def _write_serial_clean_worker_evidence_8616(
    source_project: object,
    evidence_path: Path,
    *,
    evidence_by_addr: object = None,
) -> cython.longlong:
    """Write typed discovery evidence needed by an isolated clean worker."""
    program_summaries: object
    project_layout: object
    source_evidence: object
    if evidence_by_addr is None:
        evidence_by_addr = caller_return_use_evidence_by_addr_8616(source_project)
    layouts, ranges = _widening_payload_8616(source_project)
    pointer_evidence = callee_pointer_argument_evidence_by_addr_8616(source_project)
    source_evidence = project_global_object_source_evidence_8616(source_project)
    program_summaries = program_callsite_summary_evidence_8616(source_project)
    proven_targets = tuple(
        sorted(
            target_addr
            for target_addr, evidence in builtins.iter(pointer_evidence.items())
            if evidence.closes_classification
        )
    )
    if source_evidence is not None:
        project_layout = project_global_object_layout_evidence_8616(source_project)
        if project_layout is None or operator.ne(source_evidence.layout_evidence, project_layout):
            raise ValueError("clean-worker global sources have a mismatched layout")
        if operator.ne(source_evidence.pointer_target_addrs, proven_targets):
            raise ValueError("clean-worker global sources have a mismatched pointer census")
    payload = {
        "schema": _SERIAL_CLEAN_WORKER_EVIDENCE_SCHEMA_8616,
        "scalar_interfaces": scalar_interface_records_8616(source_project),
        "scalar_interface_generation": _cache_source_digest(DECOMPILATION_CACHE_SOURCE_FILES),
        "caller_return_use": [
            {
                "function_addr": function_addr,
                "evidence": caller_return_use_evidence_record_8616(evidence),
            }
            for function_addr, evidence in builtins.iter(sorted(tuple(evidence_by_addr.items())))
        ],
        "global_object_layout": layouts,
        "bounded_global_ranges": ranges,
        "callee_pointer_evidence": callee_pointer_argument_evidence_map_record_8616(
            pointer_evidence
        ),
        "global_object_sources": (
            None
            if source_evidence is None
            else global_object_source_evidence_record_8616(source_evidence)
        ),
        "callee_callsite_censuses": callee_callsite_census_map_record_8616(
            source_project
        ),
        "program_callsite_summaries": (
            None
            if program_summaries is None
            else program_callsite_summary_evidence_record_8616(program_summaries)
        ),
    }
    evidence_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return len(evidence_by_addr)


@cython.ccall
def _caller_return_evidence_map_8616(records: object) -> object:
    """Decode validated caller-return records keyed by exact function address."""
    function_addr: object
    record: object
    evidence_by_addr: dict[cython.longlong, CallerReturnUseEvidence8616] = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("serial clean-worker caller-return entry must be an object")
        function_addr = record.get("function_addr")
        if not isinstance(function_addr, int) or isinstance(function_addr, bool) or function_addr < 0:
            raise ValueError("serial clean-worker caller-return entry has an invalid function address")
        if function_addr in evidence_by_addr:
            raise ValueError("serial clean-worker caller-return evidence contains duplicate function addresses")
        evidence_by_addr[function_addr] = caller_return_use_evidence_from_record_8616(
            record.get("evidence")
        )
    return evidence_by_addr


@cython.ccall
def _decode_layout_ranges_8616(
    payload: object,
) -> tuple[GlobalObjectLayoutEvidence8616 | None, ProjectBoundedGlobalObjectRangeEvidence8616 | None]:
    """Decode bounded-range/layout artifacts and enforce their coherence."""
    layouts: object
    ranges: object
    raw_layout: object
    raw_ranges: object
    raw_layout = payload.get("global_object_layout")
    raw_ranges = payload.get("bounded_global_ranges")
    layouts = None if raw_layout is None else global_object_layout_evidence_from_record_8616(raw_layout)
    ranges = None if raw_ranges is None else project_bounded_global_ranges_from_record_8616(raw_ranges)
    if ranges is not None and layouts is None:
        raise ValueError("serial clean-worker bounded ranges have no layout dependency")
    if ranges is not None and layouts is not None and operator.ne(ranges.layouts, layouts):
        raise ValueError("serial clean-worker Widening artifacts are incoherent")
    return layouts, ranges


def _decode_source_evidence_8616(
    payload: object,
    layouts: object,
    pointer_evidence: object,
) -> GlobalObjectSourceEvidence8616 | None:
    """Decode global object sources and check them against pointer evidence."""
    raw_sources: object
    source_evidence: object
    raw_sources = payload.get("global_object_sources")
    source_evidence = (
        None
        if raw_sources is None
        else global_object_source_evidence_from_record_8616(raw_sources)
    )
    proven_targets = tuple(
        sorted(
            target_addr
            for target_addr, evidence in builtins.iter(pointer_evidence.items())
            if evidence.closes_classification
        )
    )
    if source_evidence is not None:
        if layouts is None or operator.ne(source_evidence.layout_evidence, layouts):
            raise ValueError("serial clean-worker global sources have a mismatched layout")
        if operator.ne(source_evidence.pointer_target_addrs, proven_targets):
            raise ValueError("serial clean-worker global sources have a mismatched pointer census")
    return source_evidence


def _decode_scalar_interfaces_8616(payload: object) -> object:
    """Legacy discovery carries no scalar authority; current records bind producers."""
    raw_interfaces: object
    if payload.get("schema") == 8:
        if "scalar_interfaces" in payload or "scalar_interface_generation" in payload:
            raise ValueError("legacy evidence cannot assert scalar interfaces")
        return ()
    if operator.ne(payload.get("scalar_interface_generation"), _cache_source_digest(DECOMPILATION_CACHE_SOURCE_FILES)):
        raise ValueError("stale scalar interface producer generation")
    raw_interfaces = payload.get("scalar_interfaces")
    if not isinstance(raw_interfaces, list):
        raise ValueError("invalid scalar interface inventory")
    interfaces = tuple(scalar_interface_from_record_8616(item) for item in iter(raw_interfaces))
    if operator.ne(len({item.target for item in iter(interfaces)}), len(interfaces)):
        raise ValueError("duplicate scalar interface target")
    return interfaces


@cython.ccall
def _read_serial_clean_worker_evidence_8616(
    evidence_path: Path,
    *,
    project: object | None = None,
) -> _SerialCleanWorkerEvidence8616:
    """Read and validate discovery evidence transported to a clean worker."""
    raw_program_summaries: object
    records: object
    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid serial clean-worker evidence: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") not in (8, _SERIAL_CLEAN_WORKER_EVIDENCE_SCHEMA_8616):
        raise ValueError("serial clean-worker evidence has an unsupported schema")
    records = payload.get("caller_return_use")
    if not isinstance(records, list):
        raise ValueError("serial clean-worker caller-return evidence must be a list")
    evidence_by_addr = _caller_return_evidence_map_8616(records)
    layouts, ranges = _decode_layout_ranges_8616(payload)
    pointer_evidence = callee_pointer_argument_evidence_map_from_record_8616(
        payload.get("callee_pointer_evidence")
    )
    source_evidence = _decode_source_evidence_8616(payload, layouts, pointer_evidence)
    callsite_censuses = callee_callsite_census_map_from_record_8616(
        (
            _SERIAL_CLEAN_WORKER_DECODE_OWNER_8616
            if project is None
            else project
        ),
        payload.get("callee_callsite_censuses"),
    )
    raw_program_summaries = payload.get("program_callsite_summaries")
    program_summaries = (
        None
        if raw_program_summaries is None
        else program_callsite_summary_evidence_from_record_8616(
            raw_program_summaries
        )
    )
    interfaces = _decode_scalar_interfaces_8616(payload)
    return _SerialCleanWorkerEvidence8616(
        evidence_by_addr,
        layouts,
        ranges,
        pointer_evidence,
        source_evidence,
        callsite_censuses,
        program_summaries,
        interfaces,
    )


@cython.ccall
def _hydrate_serial_clean_worker_evidence_8616(project: object) -> cython.longlong:
    """Attach parent discovery evidence to a clean worker's fresh project."""
    evidence_path_text: object
    evidence: object
    function_addr: object
    interface: object
    pointer_evidence: object
    evidence_path_text = os.environ.get(_SERIAL_CLEAN_WORKER_EVIDENCE_ENV_8616)
    if not evidence_path_text:
        return 0
    transported = _read_serial_clean_worker_evidence_8616(
        Path(evidence_path_text),
        project=project,
    )
    for interface in transported.scalar_interfaces:
        attach_scalar_interface_8616(project, interface)
    for function_addr, evidence in transported.caller_return_use_by_addr.items():
        record_caller_return_use_evidence_8616(project, function_addr, evidence)
    if transported.global_object_layout is not None:
        attach_project_global_object_layout_evidence_8616(
            project,
            transported.global_object_layout,
        )
    if transported.bounded_global_ranges is not None:
        attach_project_bounded_global_object_ranges_8616(
            project,
            transported.bounded_global_ranges,
        )
    for pointer_evidence in transported.callee_pointer_by_addr.values():
        record_callee_pointer_argument_evidence_8616(project, pointer_evidence)
    if transported.global_object_sources is not None:
        attach_project_global_object_source_evidence_8616(
            project,
            transported.global_object_sources,
        )
    attach_callee_callsite_censuses_8616(
        project,
        transported.callee_callsites_by_addr,
    )
    if transported.program_callsite_summaries is not None:
        attach_program_callsite_summary_evidence_8616(
            project,
            transported.program_callsite_summaries,
        )
    return len(transported.caller_return_use_by_addr)


__all__ = [
    "_SERIAL_CLEAN_WORKER_EVIDENCE_ENV_8616",
    "_hydrate_serial_clean_worker_evidence_8616",
    "_read_serial_clean_worker_evidence_8616",
    "_write_serial_clean_worker_evidence_8616",
]
