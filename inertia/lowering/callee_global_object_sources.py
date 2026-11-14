# cython: language_level=3, infer_types=True
"""Collect project-wide global object-family source facts.

Layer: Types/Lowering.
Responsibility: join complete callee source-family facts across binary-proven
pointer targets and refuse conflicting family identities for one storage base.
Consumes alias, widening, and typed facts. This module does not mutate codegen.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, cast

from inertia.widening.global_object_layout import GlobalObjectLayoutEvidence8616

from .callee_global_object_collection import (
    collect_callee_global_object_interface_evidence_8616,
)
from .callee_global_object_evidence import CalleeGlobalObjectSourceFamilyFact8616
from .callee_pointer_contracts import (
    CalleePointerArgumentEvidence8616,
    callee_pointer_argument_evidence_by_addr_8616,
)
import dataclasses
import operator
import builtins

_LOGGER = logging.getLogger(__name__)


class _ProjectSourceEvidenceSurface8616(Protocol):
    """Owned project caches used by project-wide source-family collection."""

    _inertia_project_global_object_source_evidence_8616: GlobalObjectSourceEvidence8616


@dataclasses.dataclass(frozen=True, )
class GlobalObjectSourceEvidence8616:
    """Closed census of callee-proven global object sources in one scope."""

    scope_addr: int | None
    source_facts: object
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    pointer_target_addrs: tuple[cython.longlong, ...] = ()
    layout_evidence: GlobalObjectLayoutEvidence8616 | None = None

    def _validate_counters_8616(self) -> None:
        """Reject incoherent or non-monotonic collection counters."""
        counters = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        if any(count < 0 for count in iter(counters)):
            raise ValueError("global source evidence counters must be nonnegative")
        if not (
            self.raw_fact_count >= self.normalized_fact_count >= self.classified_fact_count
        ):
            raise ValueError("global source evidence counters are not monotonic")
        if operator.ne(self.classified_fact_count, len(self.source_facts)):
            raise ValueError("global source evidence classified count disagrees with facts")
        if self.materialized_count > self.classified_fact_count:
            raise ValueError("global source evidence materialized count exceeds classification")
        if self.failure_count < self.raw_fact_count - self.classified_fact_count:
            raise ValueError("global source evidence failure count does not close collection")

    def _validate_pointer_targets_8616(self) -> None:
        """Reject non-canonical or negative pointer target identities."""
        if operator.ne(self.pointer_target_addrs, tuple(sorted(tuple(set(self.pointer_target_addrs))))):
            raise ValueError("global source evidence pointer targets are not canonical")
        if any(target_addr < 0 for target_addr in iter(self.pointer_target_addrs)):
            raise ValueError("global source evidence has a negative pointer target")

    def _validate_layout_dependency_8616(self) -> None:
        """Reject missing, open, or undeclared layout/pointer dependencies."""
        if self.scope_addr is None and self.layout_evidence is None:
            raise ValueError("project global source evidence has no layout dependency")
        if self.layout_evidence is not None and not self.layout_evidence.closed:
            raise ValueError("global source evidence layout dependency is open")
        if self.scope_addr is None and any(
            fact.target_addr not in self.pointer_target_addrs for fact in iter(self.source_facts)
        ):
            raise ValueError("project global source fact has no pointer-target dependency")

    def validate(self) -> None:
        """Reject incoherent collection counters or project target identity."""
        self._validate_counters_8616()
        self._validate_pointer_targets_8616()
        self._validate_layout_dependency_8616()


@cython.ccall
def project_global_object_source_evidence_8616(
    project: object,
) -> GlobalObjectSourceEvidence8616 | None:
    """Return attached project-wide source evidence when structurally valid."""
    surface = cast(_ProjectSourceEvidenceSurface8616, project)
    try:
        evidence = surface._inertia_project_global_object_source_evidence_8616
    except AttributeError:
        return None
    if not isinstance(evidence, GlobalObjectSourceEvidence8616):
        raise TypeError("project global source evidence has a wrong type")
    evidence.validate()
    if evidence.scope_addr is not None:
        raise ValueError("attached project global source evidence has a local scope")
    return evidence


@cython.ccall
def attach_project_global_object_source_evidence_8616(
    project: object,
    evidence: GlobalObjectSourceEvidence8616,
) -> None:
    """Attach one already-classified project-wide source-family census."""
    evidence.validate()
    if evidence.scope_addr is not None:
        raise ValueError("cannot attach local-scope global source evidence to a project")
    cast(
        _ProjectSourceEvidenceSurface8616,
        project,
    )._inertia_project_global_object_source_evidence_8616 = evidence


def join_global_object_source_facts_8616(
    scope_addr: int | None,
    source_facts: Iterable[CalleeGlobalObjectSourceFamilyFact8616],
    pointer_target_addrs: object = (),
    *,
    layout_evidence: GlobalObjectLayoutEvidence8616 | None = None,
) -> GlobalObjectSourceEvidence8616:
    """Join source facts by storage base and refuse family conflicts."""
    fact: object
    normalized = tuple(source_facts)
    families_by_base: dict[cython.longlong, set[cython.longlong]] = {}
    for fact in normalized:
        families_by_base.setdefault(fact.base_offset & 0xFFFF, set()).add(
            fact.family_base_offset & 0xFFFF
        )
    conflicted_bases = {
        base_offset
        for base_offset, families in builtins.iter(families_by_base.items())
        if len(families) != 1
    }
    classified = tuple(
        fact
        for fact in iter(normalized)
        if (fact.base_offset & 0xFFFF) not in conflicted_bases
    )
    return GlobalObjectSourceEvidence8616(
        scope_addr=scope_addr,
        source_facts=classified,
        raw_fact_count=len(normalized),
        normalized_fact_count=len(normalized),
        classified_fact_count=len(classified),
        materialized_count=0,
        failure_count=len(normalized) - len(classified),
        pointer_target_addrs=pointer_target_addrs,
        layout_evidence=layout_evidence,
    )


def _proven_pointer_target_addresses_8616(project: object) -> tuple[cython.longlong, ...]:
    """Return targets with a complete binary pointer-argument contract."""
    registry = callee_pointer_argument_evidence_by_addr_8616(project)
    return tuple(
        sorted(
            target_addr
            for target_addr, evidence in builtins.iter(registry.items())
            if isinstance(target_addr, int)
            and isinstance(evidence, CalleePointerArgumentEvidence8616)
            and evidence.failure_count == 0
            and evidence.classified_fact_count > 0
            and operator.eq(evidence.materialized_count, evidence.classified_fact_count)
        )
    )


@cython.ccall
def collect_project_global_object_source_evidence_8616(
    project: object,
    layout_evidence: GlobalObjectLayoutEvidence8616,
) -> GlobalObjectSourceEvidence8616:
    """Collect and cache source-family facts across proven pointer callees."""
    target_addr: object
    surface = cast(_ProjectSourceEvidenceSurface8616, project)
    try:
        cached = surface._inertia_project_global_object_source_evidence_8616
    except AttributeError:
        cached = None
    pointer_targets = _proven_pointer_target_addresses_8616(project)
    if (
        isinstance(cached, GlobalObjectSourceEvidence8616)
        and operator.eq(cached.pointer_target_addrs, pointer_targets)
        and operator.eq(cached.layout_evidence, layout_evidence)
    ):
        cached.validate()
        return cached
    facts: list[CalleeGlobalObjectSourceFamilyFact8616] = []
    for target_addr in pointer_targets:
        evidence = collect_callee_global_object_interface_evidence_8616(
            project,
            target_addr,
            layout_evidence,
        )
        facts.extend(evidence.source_facts)
        if os.environ.get("INERTIA_DEBUG_CALLEE_GLOBAL_OBJECT_SOURCES") == "1":
            _LOGGER.warning(
                "project global object source target=%#x callee_family=%s "
                "callee_callsites=%s source_facts=%s",
                target_addr,
                evidence.family_base_offset,
                evidence.callsite_addrs,
                evidence.source_facts,
            )
    joined = join_global_object_source_facts_8616(
        None,
        facts,
        pointer_targets,
        layout_evidence=layout_evidence,
    )
    attach_project_global_object_source_evidence_8616(project, joined)
    if os.environ.get("INERTIA_DEBUG_CALLEE_GLOBAL_OBJECT_SOURCES") == "1":
        _LOGGER.warning("project global object source joined=%s", joined)
    return joined


__all__ = [
    "GlobalObjectSourceEvidence8616",
    "attach_project_global_object_source_evidence_8616",
    "collect_project_global_object_source_evidence_8616",
    "join_global_object_source_facts_8616",
    "project_global_object_source_evidence_8616",
]
