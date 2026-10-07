"""Join project-wide direct ordering facts to proven wide global objects.

Layer: Types/Lowering orchestration.
Responsibility: collect exact binary ordering facts across known function
bounds and attach signedness only to an independently widened DS object.
This module does not mutate C declarations or inspect rendered C.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, cast

from inertia.semantics.direct_global_ordering import (
    DirectGlobalOrdering8616,
    DirectGlobalOrderingFact8616,
    recover_direct_global_ordering_facts_8616,
)
from inertia.widening.global_object_layout import DirectGlobalObjectLayoutEvidence8616

from .project_global_object_layout import FunctionRangeView8616
from .real_mode_linear import _direct_global_update_ordered_insns_8616
from .segmented_global_loads import _capstone_instruction_view_8616


@dataclass(frozen=True, slots=True)
class ProjectGlobalOrderingView8616:
    """One direct ordering fact attributed to an exact function range."""

    function_addr: int
    fact: DirectGlobalOrderingFact8616


@dataclass(frozen=True, slots=True)
class ProjectGlobalSignednessContract8616:
    """One conflict-free signedness contract for a proven wide DS object."""

    base_offset: int
    ordering: DirectGlobalOrdering8616
    proof_function_addrs: tuple[int, ...]
    proof_compare_addrs: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ProjectGlobalSignednessEvidence8616:
    """Closed census and contracts for project-wide global signedness."""

    contracts: tuple[ProjectGlobalSignednessContract8616, ...] = ()
    conflicting_base_offsets: tuple[int, ...] = ()
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


class ProjectGlobalOrderingCollector8616(Protocol):
    """Collector contract for one exact function boundary."""

    def __call__(
        self,
        project: object,
        function: object,
    ) -> Iterable[DirectGlobalOrderingFact8616]:
        """Return exact direct ordering facts for one function."""
        ...


type ProjectGlobalOrderingCollectorTuple8616 = tuple[ProjectGlobalOrderingCollector8616, ...]


class _ProjectGlobalSignednessSurface8616(Protocol):
    """Owned metadata attached to an angr project at the dynamic boundary."""

    _inertia_caller_function_ranges_8616: tuple[tuple[int, int], ...]
    _inertia_original_project: object
    _inertia_project_direct_global_object_layout_evidence_8616: DirectGlobalObjectLayoutEvidence8616
    _inertia_project_global_signedness_evidence_8616: ProjectGlobalSignednessEvidence8616


def recover_project_global_signedness_evidence_8616(
    layout_evidence: DirectGlobalObjectLayoutEvidence8616,
    views: Iterable[ProjectGlobalOrderingView8616],
) -> ProjectGlobalSignednessEvidence8616:
    """Join direct high-word ordering facts to proven wide DS layouts."""
    raw_views = tuple(views)
    normalized = tuple(dict.fromkeys(raw_views))
    by_base: dict[int, list[ProjectGlobalOrderingView8616]] = {}
    high_to_base = {
        ((layout.address.offset + 2) & 0xFFFF): layout.address.offset & 0xFFFF
        for layout in layout_evidence.layouts
        if layout.address.size >= 4
    }
    for view in normalized:
        base_offset = high_to_base.get(view.fact.offset & 0xFFFF)
        if base_offset is not None:
            by_base.setdefault(base_offset, []).append(view)

    contracts: list[ProjectGlobalSignednessContract8616] = []
    conflicts: list[int] = []
    classified_count = 0
    failure_count = 0
    for base_offset, grouped_views in sorted(by_base.items()):
        orderings = {view.fact.ordering for view in grouped_views}
        if len(orderings) != 1:
            conflicts.append(base_offset)
            failure_count += len(grouped_views)
            continue
        ordering = next(iter(orderings))
        classified_count += len(grouped_views)
        contracts.append(
            ProjectGlobalSignednessContract8616(
                base_offset=base_offset,
                ordering=ordering,
                proof_function_addrs=tuple(sorted({view.function_addr for view in grouped_views})),
                proof_compare_addrs=tuple(sorted({view.fact.compare_ins_addr for view in grouped_views})),
            )
        )
    return ProjectGlobalSignednessEvidence8616(
        contracts=tuple(contracts),
        conflicting_base_offsets=tuple(conflicts),
        raw_fact_count=len(raw_views),
        normalized_fact_count=len(normalized),
        classified_fact_count=classified_count,
        materialized_count=len(contracts),
        failure_count=failure_count,
    )


def collect_direct_global_ordering_facts_8616(
    project: object,
    function: object,
) -> tuple[DirectGlobalOrderingFact8616, ...]:
    """Collect typed direct ordering facts from one exact function range."""
    instructions = _direct_global_update_ordered_insns_8616(project, function)
    return recover_direct_global_ordering_facts_8616(
        _capstone_instruction_view_8616(instruction) for instruction in instructions
    )


def collect_project_global_signedness_evidence_8616(
    project: object,
    collectors: ProjectGlobalOrderingCollectorTuple8616 = (collect_direct_global_ordering_facts_8616,),
) -> ProjectGlobalSignednessEvidence8616:
    """Collect and cache project-wide signedness for proven wide DS objects."""
    surface = cast(_ProjectGlobalSignednessSurface8616, project)
    try:
        cached = surface._inertia_project_global_signedness_evidence_8616
    except AttributeError:
        cached = None
    if isinstance(cached, ProjectGlobalSignednessEvidence8616):
        return cached
    try:
        layouts = surface._inertia_project_direct_global_object_layout_evidence_8616
        ranges = surface._inertia_caller_function_ranges_8616
    except AttributeError:
        return ProjectGlobalSignednessEvidence8616()
    if not isinstance(layouts, DirectGlobalObjectLayoutEvidence8616):
        raise TypeError("project direct-global layout evidence has an invalid type")
    if not isinstance(ranges, tuple):
        raise TypeError("project function ranges must be a tuple of (start, end) pairs")
    try:
        evidence_project = surface._inertia_original_project
    except AttributeError:
        evidence_project = project

    views: list[ProjectGlobalOrderingView8616] = []
    for bounds in ranges:
        if (
            not isinstance(bounds, tuple)
            or len(bounds) != 2
            or not isinstance(bounds[0], int)
            or not isinstance(bounds[1], int)
            or bounds[1] <= bounds[0]
        ):
            raise TypeError("project function ranges contain an invalid (start, end) pair")
        function = FunctionRangeView8616(addr=bounds[0], size=bounds[1] - bounds[0])
        for collector in collectors:
            views.extend(
                ProjectGlobalOrderingView8616(function.addr, fact)
                for fact in collector(evidence_project, function)
            )
    result = recover_project_global_signedness_evidence_8616(layouts, views)
    surface._inertia_project_global_signedness_evidence_8616 = result
    return result


__all__ = [
    "ProjectGlobalOrderingView8616",
    "ProjectGlobalSignednessContract8616",
    "ProjectGlobalSignednessEvidence8616",
    "collect_direct_global_ordering_facts_8616",
    "collect_project_global_signedness_evidence_8616",
    "recover_project_global_signedness_evidence_8616",
]
