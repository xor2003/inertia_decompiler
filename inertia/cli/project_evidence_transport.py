"""Transport typed evidence across CLI-created project boundaries.

Layer: CLI/fallback/reporting.
Responsibility: copy already-derived typed evidence into retry and slice projects
without reclassifying, rebasing, or inferring decompiler semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from inertia.lowering.callee_callsite_contracts import (
    CalleeCallsiteCensus8616,
    attach_callee_callsite_censuses_8616,
    callee_callsite_censuses_by_addr_8616,
)
from inertia.lowering.callee_global_object_sources import (
    attach_project_global_object_source_evidence_8616,
    project_global_object_source_evidence_8616,
)
from inertia.lowering.callee_pointer_contracts import (
    callee_pointer_argument_evidence_by_addr_8616,
    record_callee_pointer_argument_evidence_8616,
)
from inertia.semantics.callsite_summary import (
    caller_return_use_evidence_by_addr_8616,
    record_caller_return_use_evidence_8616,
)
from inertia.semantics.callsite_summary_program import (
    attach_program_callsite_summary_evidence_8616,
    program_callsite_summary_evidence_8616,
)
from inertia.semantics.compiler_helpers import transfer_x86_16_compiler_helper_evidence_8616
from inertia.widening.direct_global_object_layout_codec import (
    validate_direct_global_object_layout_evidence_8616,
)
from inertia.widening.global_object_layout import (
    DirectGlobalObjectLayoutEvidence8616,
    GlobalObjectLayoutEvidence8616,
)
from inertia.widening.indexed_global_object_program_ranges import (
    ProjectBoundedGlobalObjectRangeEvidence8616,
)

__all__ = [
    "ProjectEvidenceTransferResult8616",
    "attach_project_bounded_global_object_ranges_8616",
    "attach_project_direct_global_object_layout_evidence_8616",
    "attach_project_global_object_layout_evidence_8616",
    "project_bounded_global_object_ranges_8616",
    "project_direct_global_object_layout_evidence_8616",
    "project_global_object_layout_evidence_8616",
    "transfer_callee_callsite_censuses_8616",
    "transfer_caller_return_use_evidence_8616",
    "transfer_program_callsite_summary_evidence_8616",
    "transfer_project_evidence_8616",
    "transfer_project_global_source_evidence_8616",
]


@dataclass(frozen=True, slots=True)
class ProjectEvidenceTransferResult8616:
    """Counts of typed evidence copied across one CLI project boundary."""

    caller_return_use_count: int
    compiler_helper_target_count: int
    global_object_layout_artifact_count: int
    bounded_global_range_artifact_count: int
    direct_global_object_layout_artifact_count: int
    callee_pointer_target_count: int
    global_object_source_artifact_count: int
    callee_callsite_census_count: int = 0
    program_callsite_summary_artifact_count: int = 0


class _ProjectGlobalLayoutSurface8616(Protocol):
    """Owned Widening artifact attached at the dynamic project boundary."""

    _inertia_project_global_object_layout_evidence_8616: GlobalObjectLayoutEvidence8616
    _inertia_project_bounded_global_object_ranges_8616: ProjectBoundedGlobalObjectRangeEvidence8616
    _inertia_project_direct_global_object_layout_evidence_8616: DirectGlobalObjectLayoutEvidence8616


class _RebasedProjectSurface8616(Protocol):
    """Explicit relation from a rebased slice to its source project."""

    _inertia_original_project: object
    _inertia_original_linear_delta: int


def project_global_object_layout_evidence_8616(
    project: object,
) -> GlobalObjectLayoutEvidence8616 | None:
    """Return one valid attached Widening artifact, when present."""
    try:
        evidence = cast(
            _ProjectGlobalLayoutSurface8616,
            project,
        )._inertia_project_global_object_layout_evidence_8616
    except AttributeError:
        return None
    if not isinstance(evidence, GlobalObjectLayoutEvidence8616):
        raise TypeError("project indexed-global Widening artifact has a wrong type")
    if not evidence.closed:
        raise ValueError("project indexed-global Widening artifact is open")
    return evidence


def attach_project_global_object_layout_evidence_8616(
    project: object,
    evidence: GlobalObjectLayoutEvidence8616,
) -> None:
    """Attach one already-classified closed Widening artifact."""
    if not evidence.closed:
        raise ValueError("cannot attach open indexed-global Widening evidence")
    cast(
        _ProjectGlobalLayoutSurface8616,
        project,
    )._inertia_project_global_object_layout_evidence_8616 = evidence


def project_bounded_global_object_ranges_8616(
    project: object,
) -> ProjectBoundedGlobalObjectRangeEvidence8616 | None:
    """Return one valid attached bounded-range artifact, when present."""
    try:
        evidence = cast(
            _ProjectGlobalLayoutSurface8616,
            project,
        )._inertia_project_bounded_global_object_ranges_8616
    except AttributeError:
        return None
    if not isinstance(evidence, ProjectBoundedGlobalObjectRangeEvidence8616):
        raise TypeError("project bounded-global Widening artifact has a wrong type")
    if not evidence.closed:
        raise ValueError("project bounded-global Widening artifact is open")
    return evidence


def attach_project_bounded_global_object_ranges_8616(
    project: object,
    evidence: ProjectBoundedGlobalObjectRangeEvidence8616,
) -> None:
    """Attach one already-classified closed bounded-range artifact."""
    if not evidence.closed:
        raise ValueError("cannot attach open bounded-global Widening evidence")
    cast(
        _ProjectGlobalLayoutSurface8616,
        project,
    )._inertia_project_bounded_global_object_ranges_8616 = evidence


def project_direct_global_object_layout_evidence_8616(
    project: object,
) -> DirectGlobalObjectLayoutEvidence8616 | None:
    """Return one valid attached direct-global Widening census, when present."""
    try:
        evidence = cast(
            _ProjectGlobalLayoutSurface8616,
            project,
        )._inertia_project_direct_global_object_layout_evidence_8616
    except AttributeError:
        return None
    if not isinstance(evidence, DirectGlobalObjectLayoutEvidence8616):
        raise TypeError("project direct-global Widening artifact has a wrong type")
    validate_direct_global_object_layout_evidence_8616(evidence)
    return evidence


def attach_project_direct_global_object_layout_evidence_8616(
    project: object,
    evidence: DirectGlobalObjectLayoutEvidence8616,
) -> None:
    """Attach one already-classified closed direct-global census."""
    validate_direct_global_object_layout_evidence_8616(evidence)
    cast(
        _ProjectGlobalLayoutSurface8616,
        project,
    )._inertia_project_direct_global_object_layout_evidence_8616 = evidence


def transfer_caller_return_use_evidence_8616(
    source_project: object,
    destination_project: object,
) -> int:
    """Copy typed caller-use facts across one CLI project boundary."""
    evidence_by_addr = caller_return_use_evidence_by_addr_8616(source_project)
    if source_project is destination_project:
        return len(evidence_by_addr)
    for function_addr, evidence in evidence_by_addr.items():
        record_caller_return_use_evidence_8616(destination_project, function_addr, evidence)
    return len(evidence_by_addr)


def transfer_program_callsite_summary_evidence_8616(
    source_project: object,
    destination_project: object,
) -> int:
    """Copy one immutable caller-indexed summary artifact without rebuilding it."""
    evidence = program_callsite_summary_evidence_8616(source_project)
    if evidence is not None and source_project is not destination_project:
        attach_program_callsite_summary_evidence_8616(destination_project, evidence)
    return int(evidence is not None)


def _destination_census_target_8616(
    source_project: object,
    destination_project: object,
    target_addr: int,
) -> int | None:
    """Map a source-binary target onto one explicit rebased destination."""
    try:
        destination = cast(_RebasedProjectSurface8616, destination_project)
        original = destination._inertia_original_project
        delta = destination._inertia_original_linear_delta
    except AttributeError:
        return target_addr
    if original is not source_project or not isinstance(delta, int):
        return target_addr
    mapped = target_addr - delta
    return mapped if mapped >= 0 else None


def transfer_callee_callsite_censuses_8616(
    source_project: object,
    destination_project: object,
) -> int:
    """Copy raw caller facts and add exact rebased target aliases when needed."""
    source = callee_callsite_censuses_by_addr_8616(source_project)
    if source_project is destination_project:
        return len(source)
    destination = dict(callee_callsite_censuses_by_addr_8616(destination_project))
    for target_addr, census in source.items():
        destination[target_addr] = census
        mapped_target = _destination_census_target_8616(
            source_project,
            destination_project,
            target_addr,
        )
        if mapped_target is not None and mapped_target != target_addr:
            destination[mapped_target] = CalleeCallsiteCensus8616(
                target_addr=mapped_target,
                facts=census.facts,
                raw_fact_count=census.raw_fact_count,
                normalized_fact_count=census.normalized_fact_count,
                failure_count=census.failure_count,
            )
    attach_callee_callsite_censuses_8616(destination_project, destination)
    return len(source)


def transfer_project_global_source_evidence_8616(
    source_project: object,
    destination_project: object,
) -> tuple[int, int]:
    """Copy one coherent pointer-registry and layout-bound source artifact."""
    pointer_evidence = callee_pointer_argument_evidence_by_addr_8616(source_project)
    source_evidence = project_global_object_source_evidence_8616(source_project)
    proven_targets = tuple(
        sorted(
            target_addr
            for target_addr, evidence in pointer_evidence.items()
            if evidence.closes_classification
        )
    )
    if source_evidence is not None:
        global_layout = project_global_object_layout_evidence_8616(source_project)
        if global_layout is None or source_evidence.layout_evidence != global_layout:
            raise ValueError("project global-source evidence has a mismatched layout")
        if source_evidence.pointer_target_addrs != proven_targets:
            raise ValueError("project global-source evidence has a mismatched pointer census")
    if source_project is not destination_project:
        for evidence in pointer_evidence.values():
            record_callee_pointer_argument_evidence_8616(destination_project, evidence)
        if source_evidence is not None:
            destination_layout = project_global_object_layout_evidence_8616(
                destination_project
            )
            if destination_layout != source_evidence.layout_evidence:
                raise ValueError("destination project has a mismatched global-source layout")
            attach_project_global_object_source_evidence_8616(
                destination_project,
                source_evidence,
            )
    return len(pointer_evidence), int(source_evidence is not None)


def transfer_project_evidence_8616(
    source_project: object,
    destination_project: object,
) -> ProjectEvidenceTransferResult8616:
    """Copy all typed evidence required by fresh and sliced CLI projects."""
    global_layout = project_global_object_layout_evidence_8616(source_project)
    bounded_ranges = project_bounded_global_object_ranges_8616(source_project)
    direct_layout = project_direct_global_object_layout_evidence_8616(source_project)
    if bounded_ranges is not None and global_layout is None:
        raise ValueError("bounded-global evidence has no project layout dependency")
    if (
        bounded_ranges is not None
        and global_layout is not None
        and bounded_ranges.layouts != global_layout
    ):
        raise ValueError("bounded-global evidence disagrees with project layouts")
    if global_layout is not None and source_project is not destination_project:
        attach_project_global_object_layout_evidence_8616(
            destination_project,
            global_layout,
        )
        if bounded_ranges is not None:
            attach_project_bounded_global_object_ranges_8616(
                destination_project,
                bounded_ranges,
            )
    if direct_layout is not None and source_project is not destination_project:
        attach_project_direct_global_object_layout_evidence_8616(
            destination_project,
            direct_layout,
        )
    pointer_count, source_count = transfer_project_global_source_evidence_8616(
        source_project,
        destination_project,
    )
    return ProjectEvidenceTransferResult8616(
        caller_return_use_count=transfer_caller_return_use_evidence_8616(
            source_project,
            destination_project,
        ),
        compiler_helper_target_count=transfer_x86_16_compiler_helper_evidence_8616(
            source_project,
            destination_project,
        ),
        global_object_layout_artifact_count=int(global_layout is not None),
        bounded_global_range_artifact_count=int(bounded_ranges is not None),
        direct_global_object_layout_artifact_count=int(direct_layout is not None),
        callee_pointer_target_count=pointer_count,
        global_object_source_artifact_count=source_count,
        callee_callsite_census_count=transfer_callee_callsite_censuses_8616(
            source_project,
            destination_project,
        ),
        program_callsite_summary_artifact_count=(
            transfer_program_callsite_summary_evidence_8616(
                source_project,
                destination_project,
            )
        ),
    )
