"""Transport typed project evidence into isolated clean workers.

Layer: CLI/fallback/reporting.
Responsibility: encode, validate, and attach already-derived caller-use and
Widening artifacts across the parent-to-worker JSON boundary. No semantic fact
is inferred, rebuilt, or reclassified here.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from angr_platforms.X86_16.callsite_summary import (
    CallerReturnUseEvidence8616,
    caller_return_use_evidence_by_addr_8616,
    record_caller_return_use_evidence_8616,
)
from angr_platforms.X86_16.callsite_summary_program import (
    ProgramCallsiteSummaryEvidence8616,
    attach_program_callsite_summary_evidence_8616,
    program_callsite_summary_evidence_8616,
)
from angr_platforms.X86_16.callsite_summary_program_codec import (
    program_callsite_summary_evidence_from_record_8616,
    program_callsite_summary_evidence_record_8616,
)
from angr_platforms.X86_16.lowering.callee_callsite_codec import (
    callee_callsite_census_map_from_record_8616,
    callee_callsite_census_map_record_8616,
)
from angr_platforms.X86_16.lowering.callee_callsite_contracts import (
    CalleeCallsiteCensus8616,
    attach_callee_callsite_censuses_8616,
)
from angr_platforms.X86_16.lowering.callee_global_object_sources import (
    GlobalObjectSourceEvidence8616,
    attach_project_global_object_source_evidence_8616,
    project_global_object_source_evidence_8616,
)
from angr_platforms.X86_16.lowering.callee_pointer_codec import (
    callee_pointer_argument_evidence_map_from_record_8616,
    callee_pointer_argument_evidence_map_record_8616,
)
from angr_platforms.X86_16.lowering.callee_pointer_contracts import (
    CalleePointerArgumentEvidence8616,
    callee_pointer_argument_evidence_by_addr_8616,
    record_callee_pointer_argument_evidence_8616,
)
from angr_platforms.X86_16.lowering.global_object_source_codec import (
    global_object_source_evidence_from_record_8616,
    global_object_source_evidence_record_8616,
)
from angr_platforms.X86_16.widening.global_object_layout import (
    GlobalObjectLayoutEvidence8616,
)
from angr_platforms.X86_16.widening.global_object_layout_codec import (
    global_object_layout_evidence_from_record_8616,
    global_object_layout_evidence_record_8616,
)
from angr_platforms.X86_16.widening.indexed_global_object_program_range_codec import (
    project_bounded_global_ranges_from_record_8616,
    project_bounded_global_ranges_record_8616,
)
from angr_platforms.X86_16.widening.indexed_global_object_program_ranges import (
    ProjectBoundedGlobalObjectRangeEvidence8616,
)

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

_SERIAL_CLEAN_WORKER_EVIDENCE_ENV_8616 = "INERTIA_SERIAL_CLEAN_WORKER_EVIDENCE"
_SERIAL_CLEAN_WORKER_EVIDENCE_SCHEMA_8616 = 8
_SERIAL_CLEAN_WORKER_DECODE_OWNER_8616 = SimpleNamespace()


@dataclass(frozen=True, slots=True)
class _SerialCleanWorkerEvidence8616:
    """Typed evidence decoded from one parent-to-worker payload."""

    caller_return_use_by_addr: dict[int, CallerReturnUseEvidence8616]
    global_object_layout: GlobalObjectLayoutEvidence8616 | None
    bounded_global_ranges: ProjectBoundedGlobalObjectRangeEvidence8616 | None
    callee_pointer_by_addr: dict[int, CalleePointerArgumentEvidence8616]
    global_object_sources: GlobalObjectSourceEvidence8616 | None
    callee_callsites_by_addr: dict[int, CalleeCallsiteCensus8616]
    program_callsite_summaries: ProgramCallsiteSummaryEvidence8616 | None


def _widening_payload_8616(source_project: object) -> tuple[object, object]:
    """Return coherent serialized layout and range records when available."""
    layouts = project_global_object_layout_evidence_8616(source_project)
    ranges = project_bounded_global_object_ranges_8616(source_project)
    if ranges is not None and layouts is None:
        raise ValueError("clean-worker bounded ranges have no layout dependency")
    if ranges is not None and layouts is not None and ranges.layouts != layouts:
        raise ValueError("clean-worker bounded ranges disagree with project layouts")
    return (
        None if layouts is None else global_object_layout_evidence_record_8616(layouts),
        None if ranges is None else project_bounded_global_ranges_record_8616(ranges),
    )


def _write_serial_clean_worker_evidence_8616(
    source_project: object,
    evidence_path: Path,
    *,
    evidence_by_addr: dict[int, CallerReturnUseEvidence8616] | None = None,
) -> int:
    """Write typed discovery evidence needed by an isolated clean worker."""
    if evidence_by_addr is None:
        evidence_by_addr = caller_return_use_evidence_by_addr_8616(source_project)
    layouts, ranges = _widening_payload_8616(source_project)
    pointer_evidence = callee_pointer_argument_evidence_by_addr_8616(source_project)
    source_evidence = project_global_object_source_evidence_8616(source_project)
    program_summaries = program_callsite_summary_evidence_8616(source_project)
    proven_targets = tuple(
        sorted(
            target_addr
            for target_addr, evidence in pointer_evidence.items()
            if evidence.closes_classification
        )
    )
    if source_evidence is not None:
        project_layout = project_global_object_layout_evidence_8616(source_project)
        if project_layout is None or source_evidence.layout_evidence != project_layout:
            raise ValueError("clean-worker global sources have a mismatched layout")
        if source_evidence.pointer_target_addrs != proven_targets:
            raise ValueError("clean-worker global sources have a mismatched pointer census")
    payload = {
        "schema": _SERIAL_CLEAN_WORKER_EVIDENCE_SCHEMA_8616,
        "caller_return_use": [
            {
                "function_addr": function_addr,
                "evidence": caller_return_use_evidence_record_8616(evidence),
            }
            for function_addr, evidence in sorted(evidence_by_addr.items())
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


def _read_serial_clean_worker_evidence_8616(
    evidence_path: Path,
    *,
    project: object | None = None,
) -> _SerialCleanWorkerEvidence8616:
    """Read and validate discovery evidence transported to a clean worker."""
    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid serial clean-worker evidence: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != _SERIAL_CLEAN_WORKER_EVIDENCE_SCHEMA_8616:
        raise ValueError("serial clean-worker evidence has an unsupported schema")
    records = payload.get("caller_return_use")
    if not isinstance(records, list):
        raise ValueError("serial clean-worker caller-return evidence must be a list")
    evidence_by_addr: dict[int, CallerReturnUseEvidence8616] = {}
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
    raw_layout = payload.get("global_object_layout")
    raw_ranges = payload.get("bounded_global_ranges")
    layouts = None if raw_layout is None else global_object_layout_evidence_from_record_8616(raw_layout)
    ranges = None if raw_ranges is None else project_bounded_global_ranges_from_record_8616(raw_ranges)
    if ranges is not None and layouts is None:
        raise ValueError("serial clean-worker bounded ranges have no layout dependency")
    if ranges is not None and layouts is not None and ranges.layouts != layouts:
        raise ValueError("serial clean-worker Widening artifacts are incoherent")
    pointer_evidence = callee_pointer_argument_evidence_map_from_record_8616(
        payload.get("callee_pointer_evidence")
    )
    raw_sources = payload.get("global_object_sources")
    source_evidence = (
        None
        if raw_sources is None
        else global_object_source_evidence_from_record_8616(raw_sources)
    )
    proven_targets = tuple(
        sorted(
            target_addr
            for target_addr, evidence in pointer_evidence.items()
            if evidence.closes_classification
        )
    )
    if source_evidence is not None:
        if layouts is None or source_evidence.layout_evidence != layouts:
            raise ValueError("serial clean-worker global sources have a mismatched layout")
        if source_evidence.pointer_target_addrs != proven_targets:
            raise ValueError("serial clean-worker global sources have a mismatched pointer census")
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
    return _SerialCleanWorkerEvidence8616(
        evidence_by_addr,
        layouts,
        ranges,
        pointer_evidence,
        source_evidence,
        callsite_censuses,
        program_summaries,
    )


def _hydrate_serial_clean_worker_evidence_8616(project: object) -> int:
    """Attach parent discovery evidence to a clean worker's fresh project."""
    evidence_path_text = os.environ.get(_SERIAL_CLEAN_WORKER_EVIDENCE_ENV_8616)
    if not evidence_path_text:
        return 0
    transported = _read_serial_clean_worker_evidence_8616(
        Path(evidence_path_text),
        project=project,
    )
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
    for evidence in transported.callee_pointer_by_addr.values():
        record_callee_pointer_argument_evidence_8616(project, evidence)
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
