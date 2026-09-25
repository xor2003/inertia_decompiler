"""Collect project-wide storage evidence for object layout widening.

Layer: Types/Lowering orchestration.
Responsibility: collect exact direct DS views, resolve indexed Alias program
evidence across known function bounds, and delegate object classification to
Widening. This module does not choose C types or mutate generated C.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from ..alias.indexed_address_program import (
    IndexedAliasFunctionSelection8616,
    IndexedAliasProgramEvidence8616,
    build_indexed_alias_program_evidence_8616,
)
from ..ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from ..widening.global_object_layout import (
    DirectGlobalObjectLayoutEvidence8616,
    DirectGlobalStorageView8616,
    GlobalObjectLayoutEvidence8616,
    recover_direct_global_object_layout_evidence_8616,
)
from ..widening.indexed_global_object_layout import (
    recover_global_object_layout_evidence_8616,
)


class DirectGlobalStorageEvidenceBoundary8616(Protocol):
    """Exact direct global storage fields exposed by a binary collector."""

    @property
    def offset(self) -> int:
        """Return the exact DS base displacement."""
        ...

    @property
    def width(self) -> int:
        """Return the proven object width in bytes."""
        ...


type DirectGlobalStorageEvidenceCollector8616 = Callable[
    [object, object], Iterable[DirectGlobalStorageEvidenceBoundary8616]
]


class _ProjectGlobalObjectLayoutSurface8616(Protocol):
    """Owned metadata attached to an angr project at the dynamic boundary."""

    _inertia_caller_function_ranges_8616: tuple[tuple[int, int], ...]
    _inertia_original_project: object
    _inertia_project_global_object_layout_evidence_8616: GlobalObjectLayoutEvidence8616
    _inertia_project_direct_global_object_layout_evidence_8616: DirectGlobalObjectLayoutEvidence8616
    _inertia_indexed_alias_program_evidence_8616: IndexedAliasProgramEvidence8616


class _FunctionManager8616(Protocol):
    """Third-party angr function lookup consumed at the orchestration boundary."""

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return an exact recovered function without creating one."""
        ...


class _KnowledgeBase8616(Protocol):
    """Third-party angr knowledge-base surface used for exact function lookup."""

    functions: _FunctionManager8616


class _EvidenceProject8616(Protocol):
    """Original analysis project used to rebuild earlier-layer evidence."""

    kb: _KnowledgeBase8616


@dataclass(frozen=True, slots=True)
class FunctionRangeView8616:
    """Minimal function boundary consumed by linear instruction recovery."""

    addr: int
    size: int


def _program_selections_8616(
    evidence_project: object,
    ranges: tuple[object, ...],
) -> list[IndexedAliasFunctionSelection8616]:
    """Resolve validated function-range bounds into alias selections."""
    selections: list[IndexedAliasFunctionSelection8616] = []
    for bounds in ranges:
        if (
            not isinstance(bounds, tuple)
            or len(bounds) != 2
            or not isinstance(bounds[0], int)
            or not isinstance(bounds[1], int)
            or bounds[1] <= bounds[0]
        ):
            raise TypeError(
                "project function ranges contain an invalid (start, end) pair"
            )
        try:
            function = cast(
                _EvidenceProject8616,
                evidence_project,
            ).kb.functions.function(
                addr=bounds[0],
                create=False,
            )
        except (AttributeError, KeyError, TypeError):
            function = None
        selections.append(
            IndexedAliasFunctionSelection8616(bounds[0], function)
        )
    return selections


def _indexed_alias_program_8616(
    surface: _ProjectGlobalObjectLayoutSurface8616,
    evidence_project: object,
    project: object,
    ranges: tuple[object, ...],
) -> IndexedAliasProgramEvidence8616:
    """Return cached or freshly built indexed-alias program evidence."""
    try:
        program = surface._inertia_indexed_alias_program_evidence_8616
    except AttributeError:
        program = None
    if (
        not isinstance(program, IndexedAliasProgramEvidence8616)
        and evidence_project is not project
    ):
        try:
            program = cast(
                _ProjectGlobalObjectLayoutSurface8616,
                evidence_project,
            )._inertia_indexed_alias_program_evidence_8616
        except AttributeError:
            program = None
    if not isinstance(program, IndexedAliasProgramEvidence8616):
        program = build_indexed_alias_program_evidence_8616(
            evidence_project,
            _program_selections_8616(evidence_project, ranges),
        )
        surface._inertia_indexed_alias_program_evidence_8616 = program
    return program


def collect_project_global_object_layout_evidence_8616(
    project: object,
) -> GlobalObjectLayoutEvidence8616:
    """Collect Alias program evidence and cache its Widening layouts."""
    surface = cast(_ProjectGlobalObjectLayoutSurface8616, project)
    try:
        cached = surface._inertia_project_global_object_layout_evidence_8616
    except AttributeError:
        cached = None
    if isinstance(cached, GlobalObjectLayoutEvidence8616):
        return cached

    try:
        ranges = surface._inertia_caller_function_ranges_8616
    except AttributeError:
        ranges = ()
    if not isinstance(ranges, tuple):
        raise TypeError("project function ranges must be a tuple of (start, end) pairs")

    try:
        evidence_project = surface._inertia_original_project
    except AttributeError:
        evidence_project = project

    program = _indexed_alias_program_8616(surface, evidence_project, project, ranges)
    result = recover_global_object_layout_evidence_8616(program)
    surface._inertia_project_global_object_layout_evidence_8616 = result
    return result


def collect_project_direct_global_object_layout_evidence_8616(
    project: object,
    collectors: tuple[DirectGlobalStorageEvidenceCollector8616, ...],
) -> DirectGlobalObjectLayoutEvidence8616:
    """Collect and cache exact wide direct DS views across known functions."""
    surface = cast(_ProjectGlobalObjectLayoutSurface8616, project)
    try:
        cached = surface._inertia_project_direct_global_object_layout_evidence_8616
    except AttributeError:
        cached = None
    if isinstance(cached, DirectGlobalObjectLayoutEvidence8616):
        return cached

    try:
        ranges = surface._inertia_caller_function_ranges_8616
    except AttributeError:
        ranges = ()
    if not isinstance(ranges, tuple):
        raise TypeError("project function ranges must be a tuple of (start, end) pairs")

    try:
        evidence_project = surface._inertia_original_project
    except AttributeError:
        evidence_project = project

    functions: list[FunctionRangeView8616] = []
    for bounds in ranges:
        if (
            not isinstance(bounds, tuple)
            or len(bounds) != 2
            or not isinstance(bounds[0], int)
            or not isinstance(bounds[1], int)
            or bounds[1] <= bounds[0]
        ):
            raise TypeError("project function ranges contain an invalid (start, end) pair")
        functions.append(
            FunctionRangeView8616(
                addr=bounds[0],
                size=bounds[1] - bounds[0],
            )
        )

    result = recover_project_direct_global_object_layout_evidence_8616(
        evidence_project,
        functions,
        collectors,
    )
    surface._inertia_project_direct_global_object_layout_evidence_8616 = result
    return result


def recover_project_direct_global_object_layout_evidence_8616(
    project: object,
    functions: Sequence[object],
    collectors: tuple[DirectGlobalStorageEvidenceCollector8616, ...],
) -> DirectGlobalObjectLayoutEvidence8616:
    """Recover one direct-global Widening census from explicit functions."""
    views: list[DirectGlobalStorageView8616] = []
    for function in functions:
        try:
            function_addr = cast(FunctionRangeView8616, function).addr
        except AttributeError as exc:
            raise TypeError("direct-global function has no integer address") from exc
        if not isinstance(function_addr, int) or function_addr < 0:
            raise TypeError("direct-global function has no integer address")
        for collector in collectors:
            for fact in collector(project, function):
                views.append(
                    DirectGlobalStorageView8616(
                        function_addr=function_addr,
                        address=IRAddress(
                            space=MemSpace.DS,
                            offset=fact.offset & 0xFFFF,
                            size=fact.width,
                            status=AddressStatus.STABLE,
                            segment_origin=SegmentOrigin.PROVEN,
                        ),
                    )
                )
    return recover_direct_global_object_layout_evidence_8616(views)


__all__ = [
    "DirectGlobalStorageEvidenceBoundary8616",
    "DirectGlobalStorageEvidenceCollector8616",
    "FunctionRangeView8616",
    "collect_project_direct_global_object_layout_evidence_8616",
    "collect_project_global_object_layout_evidence_8616",
    "recover_project_direct_global_object_layout_evidence_8616",
]
