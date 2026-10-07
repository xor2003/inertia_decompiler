"""Publish a complete indexed Alias program and its Widening projections.

Layer: CLI/fallback/reporting orchestration.
Responsibility: invoke the owning Alias and Widening builders once, attach their
closed artifacts, and collect dependent project evidence without reclassifying it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, cast

from inertia.alias.indexed_address_program import (
    IndexedAliasProgramEvidence8616,
)
from inertia.lowering.project_callee_callsite_collection import (
    collect_complete_project_callee_callsites_8616,
)
from inertia.lowering.project_global_object_source_collection import (
    collect_complete_project_global_object_sources_8616,
)
from inertia.widening.global_object_layout import (
    GlobalObjectLayoutEvidence8616,
)
from inertia.widening.indexed_global_object_layout import (
    recover_global_object_layout_evidence_8616,
)
from inertia.widening.indexed_global_object_program_ranges import (
    ProjectBoundedGlobalObjectRangeEvidence8616,
    recover_program_bounded_global_object_ranges_8616,
)

from . import indexed_alias_program_parallel as _alias_program_parallel


class _ProjectProgramSurface8616(Protocol):
    """Owned immutable Alias/Widening artifacts attached to a project."""

    _inertia_indexed_alias_program_evidence_8616: IndexedAliasProgramEvidence8616
    _inertia_project_global_object_layout_evidence_8616: GlobalObjectLayoutEvidence8616
    _inertia_project_bounded_global_object_ranges_8616: ProjectBoundedGlobalObjectRangeEvidence8616


def publish_discovered_indexed_alias_program_8616(
    evidence_project: object,
    functions: Sequence[object],
    *,
    target_project: object | None = None,
) -> IndexedAliasProgramEvidence8616:
    """Build Alias once and attach its closed Widening projection."""
    program = _alias_program_parallel.build_discovered_indexed_alias_program_bounded_8616(
        evidence_project,
        functions,
    )
    destination = evidence_project if target_project is None else target_project
    layouts = recover_global_object_layout_evidence_8616(program)
    ranges = recover_program_bounded_global_object_ranges_8616(program, layouts)
    evidence_surface = cast(_ProjectProgramSurface8616, evidence_project)
    evidence_surface._inertia_indexed_alias_program_evidence_8616 = program
    evidence_surface._inertia_project_global_object_layout_evidence_8616 = layouts
    evidence_surface._inertia_project_bounded_global_object_ranges_8616 = ranges
    if destination is not evidence_project:
        destination_surface = cast(_ProjectProgramSurface8616, destination)
        destination_surface._inertia_indexed_alias_program_evidence_8616 = program
        destination_surface._inertia_project_global_object_layout_evidence_8616 = layouts
        destination_surface._inertia_project_bounded_global_object_ranges_8616 = ranges
    if destination is evidence_project:
        collect_complete_project_callee_callsites_8616(evidence_project, functions)
        collect_complete_project_global_object_sources_8616(
            evidence_project,
            functions,
            layouts,
        )
    return program


__all__ = ["publish_discovered_indexed_alias_program_8616"]
