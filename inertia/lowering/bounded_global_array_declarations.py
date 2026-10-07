"""Materialize exact global array extents from project Widening evidence.

Layer: Types/Lowering.
Responsibility: bind an accepted segmented bounded range to one exact existing
indexed-global name, then strengthen only that declaration's array extent.
Dynamic bounds, Widening refusals, ambiguous names, and missing declarations
remain explicit and never create a guessed array.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from inertia.pipeline.errors import PipelineHardError

from inertia.widening.indexed_global_object_program_ranges import (
    ProjectBoundedGlobalObjectRangeEvidence8616,
)
from inertia.widening.indexed_global_object_ranges import (
    BoundedGlobalObjectRange8616,
    BoundedGlobalObjectRangeRefusal8616,
)

from .global_declaration_extents import (
    GlobalDeclarationExtentApplication8616,
    GlobalDeclarationExtentApplicationStatus8616,
    apply_existing_global_array_extent_8616,
)
from .indexed_global_evidence import IndexedSegmentedGlobalEvidence8616


class BoundedGlobalArrayLoweringStatus8616(StrEnum):
    """Typed availability status of project bounded-range evidence."""

    NOT_AVAILABLE = "not_available"
    AVAILABLE = "available"


class BoundedGlobalArrayLoweringFailureKind8616(StrEnum):
    """Stable reason one accepted Widening range was not materialized."""

    GLOBAL_NAME_UNPROVEN = "global_name_unproven"
    GLOBAL_NAME_CONFLICT = "global_name_conflict"
    DECLARATION_MISSING = "declaration_missing"
    DECLARATION_CONFLICT = "declaration_conflict"


@dataclass(frozen=True, slots=True)
class BoundedGlobalArrayDeclarationFact8616:
    """One exact range materialized as an existing named C array."""

    source: BoundedGlobalObjectRange8616
    global_name: str
    application: GlobalDeclarationExtentApplication8616

    @property
    def complete(self) -> bool:
        """Return whether name, extent, and retained declaration type agree."""
        return bool(
            self.source.complete
            and re.fullmatch(r"[A-Za-z_]\w*", self.global_name)
            and self.application.materialized
            and self.application.name == self.global_name
            and self.application.array_len == self.source.element_count
            and self.application.ctype
        )


@dataclass(frozen=True, slots=True)
class BoundedGlobalArrayDeclarationRefusal8616:
    """One accepted Widening range refused at the declaration boundary."""

    source: BoundedGlobalObjectRange8616
    failure: BoundedGlobalArrayLoweringFailureKind8616
    detail: str

    @property
    def complete(self) -> bool:
        """Return whether the refusal retains its exact source and reason."""
        return self.source.complete and bool(self.detail)


@dataclass(frozen=True, slots=True)
class BoundedGlobalArrayLoweringStats8616:
    """Closed accounting for accepted Widening ranges at Types/Lowering."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every accepted range has one declaration outcome."""
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        return bool(
            all(count >= 0 for count in counts)
            and self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count + self.failure_count
        )


@dataclass(frozen=True, slots=True)
class BoundedGlobalArrayLoweringEvidence8616:
    """Final declaration facts plus upstream and local typed refusals."""

    status: BoundedGlobalArrayLoweringStatus8616
    facts: tuple[BoundedGlobalArrayDeclarationFact8616, ...]
    refusals: tuple[BoundedGlobalArrayDeclarationRefusal8616, ...]
    upstream_refusals: tuple[BoundedGlobalObjectRangeRefusal8616, ...]
    stats: BoundedGlobalArrayLoweringStats8616
    source: ProjectBoundedGlobalObjectRangeEvidence8616 | None

    @property
    def closed(self) -> bool:
        """Return whether source availability and every local outcome agree."""
        if self.status is BoundedGlobalArrayLoweringStatus8616.NOT_AVAILABLE:
            return bool(
                self.source is None
                and not self.facts
                and not self.refusals
                and not self.upstream_refusals
                and self.stats.closed
                and self.stats.raw_fact_count == 0
            )
        return bool(
            self.source is not None
            and self.source.closed
            and self.upstream_refusals == self.source.refusals
            and self.stats.closed
            and len(self.facts) == self.stats.materialized_count
            and len(self.refusals) == self.stats.failure_count
            and len(self.source.ranges) == self.stats.raw_fact_count
            and all(fact.complete for fact in self.facts)
            and all(refusal.complete for refusal in self.refusals)
        )


class _ProjectBoundedGlobalRangeSurface8616(Protocol):
    """Owned Widening artifact attached at the project boundary."""

    _inertia_project_bounded_global_object_ranges_8616: ProjectBoundedGlobalObjectRangeEvidence8616


class _CodegenBoundedGlobalArraySurface8616(Protocol):
    """Owned Types/Lowering result attached at the codegen boundary."""

    _inertia_bounded_global_array_lowering_evidence_8616: BoundedGlobalArrayLoweringEvidence8616


def _project_ranges_8616(
    project: object,
) -> ProjectBoundedGlobalObjectRangeEvidence8616 | None:
    """Read and validate the optional project Widening artifact."""
    try:
        evidence = cast(
            _ProjectBoundedGlobalRangeSurface8616,
            project,
        )._inertia_project_bounded_global_object_ranges_8616
    except AttributeError:
        return None
    if not isinstance(evidence, ProjectBoundedGlobalObjectRangeEvidence8616):
        raise TypeError("project bounded-global Widening artifact has a wrong type")
    if not evidence.closed:
        raise ValueError("project bounded-global Widening artifact is open")
    return evidence


def _exact_global_names_8616(
    source: BoundedGlobalObjectRange8616,
    indexed_evidence: tuple[IndexedSegmentedGlobalEvidence8616, ...],
) -> tuple[str, ...]:
    """Return exact names whose base, displacement, and element width match."""
    return tuple(
        sorted(
            {
                item.name
                for item in indexed_evidence
                if item.base_offset & 0xFFFF == source.base
                and item.relative_disp == 0
                and item.width == source.element_width
                and re.fullmatch(r"[A-Za-z_]\w*", item.name)
            }
        )
    )


def _application_failure_8616(
    application: GlobalDeclarationExtentApplication8616,
) -> BoundedGlobalArrayLoweringFailureKind8616:
    """Map a typed declaration outcome to the matching local refusal."""
    if (
        application.status
        is GlobalDeclarationExtentApplicationStatus8616.DECLARATION_MISSING
    ):
        return BoundedGlobalArrayLoweringFailureKind8616.DECLARATION_MISSING
    return BoundedGlobalArrayLoweringFailureKind8616.DECLARATION_CONFLICT


def lower_project_bounded_global_arrays_8616(
    project: object,
    codegen: object,
    indexed_evidence: tuple[IndexedSegmentedGlobalEvidence8616, ...],
) -> BoundedGlobalArrayLoweringEvidence8616:
    """Apply every accepted project range to one exact existing declaration."""
    source = _project_ranges_8616(project)
    if source is None:
        return BoundedGlobalArrayLoweringEvidence8616(
            BoundedGlobalArrayLoweringStatus8616.NOT_AVAILABLE,
            (),
            (),
            (),
            BoundedGlobalArrayLoweringStats8616(),
            None,
        )
    facts: list[BoundedGlobalArrayDeclarationFact8616] = []
    refusals: list[BoundedGlobalArrayDeclarationRefusal8616] = []
    for object_range in source.ranges:
        names = _exact_global_names_8616(object_range, indexed_evidence)
        if not names:
            refusals.append(
                BoundedGlobalArrayDeclarationRefusal8616(
                    object_range,
                    BoundedGlobalArrayLoweringFailureKind8616.GLOBAL_NAME_UNPROVEN,
                    "no exact indexed-global declaration name matches the bounded range",
                )
            )
            continue
        if len(names) != 1:
            refusals.append(
                BoundedGlobalArrayDeclarationRefusal8616(
                    object_range,
                    BoundedGlobalArrayLoweringFailureKind8616.GLOBAL_NAME_CONFLICT,
                    "multiple indexed-global declaration names match the bounded range",
                )
            )
            continue
        application = apply_existing_global_array_extent_8616(
            codegen,
            name=names[0],
            array_len=object_range.element_count,
        )
        if application.materialized:
            facts.append(
                BoundedGlobalArrayDeclarationFact8616(
                    object_range,
                    names[0],
                    application,
                )
            )
        else:
            refusals.append(
                BoundedGlobalArrayDeclarationRefusal8616(
                    object_range,
                    _application_failure_8616(application),
                    f"existing global declaration extent refused: {application.status.value}",
                )
            )
    count = len(source.ranges)
    result = BoundedGlobalArrayLoweringEvidence8616(
        BoundedGlobalArrayLoweringStatus8616.AVAILABLE,
        tuple(facts),
        tuple(refusals),
        source.refusals,
        BoundedGlobalArrayLoweringStats8616(
            count,
            count,
            count,
            len(facts),
            len(refusals),
        ),
        source,
    )
    if not result.closed:
        raise ValueError("bounded-global array Lowering accounting did not close")
    return result


def materialize_project_bounded_global_arrays_8616(
    project: object,
    codegen: object,
    indexed_evidence: tuple[IndexedSegmentedGlobalEvidence8616, ...],
) -> bool:
    """Publish one closed result and hard-fail unmaterialized classified facts."""
    result = lower_project_bounded_global_arrays_8616(
        project,
        codegen,
        indexed_evidence,
    )
    cast(
        _CodegenBoundedGlobalArraySurface8616,
        codegen,
    )._inertia_bounded_global_array_lowering_evidence_8616 = result
    if result.stats.classified_fact_count > 0 and result.stats.materialized_count == 0:
        raise PipelineHardError(
            "classified bounded-global array ranges were not materialized "
            f"raw={result.stats.raw_fact_count} failures={result.stats.failure_count}"
        )
    return any(
        fact.application.status
        is GlobalDeclarationExtentApplicationStatus8616.APPLIED
        for fact in result.facts
    )


__all__ = [
    "BoundedGlobalArrayDeclarationFact8616",
    "BoundedGlobalArrayDeclarationRefusal8616",
    "BoundedGlobalArrayLoweringEvidence8616",
    "BoundedGlobalArrayLoweringFailureKind8616",
    "BoundedGlobalArrayLoweringStats8616",
    "BoundedGlobalArrayLoweringStatus8616",
    "lower_project_bounded_global_arrays_8616",
    "materialize_project_bounded_global_arrays_8616",
]
