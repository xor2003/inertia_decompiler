# cython: language_level=3, infer_types=True
"""Own retained direct-caller census contracts and their project registry.

Layer: Types/Lowering.
Responsibility: define exact callee callsite facts, closed census accounting,
and the authoritative project-owned registry consumed by interface lowering.
No callsites are discovered, summarized, or classified in this module.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Protocol, cast

from inertia.semantics.callsite_summary import CallsiteSummary8616
import dataclasses
import operator

__all__ = [
    "CalleeCallsiteCensus8616",
    "CalleeCallsiteFact8616",
    "attach_callee_callsite_censuses_8616",
    "callee_callsite_censuses_by_addr_8616",
    "record_callee_callsite_census_8616",
]


@dataclasses.dataclass(frozen=True, )
class CalleeCallsiteFact8616:
    """One direct call with its exact runtime evidence owner."""

    evidence_project: object = field(compare=False, repr=False)
    caller_function: object | None = field(compare=False, repr=False)
    evidence_target_addr: cython.longlong
    caller_addr: int | None
    callsite_addr: cython.longlong
    summary: CallsiteSummary8616 | None = field(compare=False)


@dataclasses.dataclass(frozen=True, )
class CalleeCallsiteCensus8616:
    """Closed normalization accounting for all discovered direct callers."""

    target_addr: cython.longlong
    facts: object
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    failure_count: cython.longlong

    @property
    def complete(self) -> cython.bint:
        """Return whether every discovered call has one typed summary."""
        return (
            self.raw_fact_count > 0
            and operator.eq(self.normalized_fact_count, self.raw_fact_count)
            and self.failure_count == 0
        )

    def validate(self) -> None:
        """Reject incoherent target identity or evidence accounting."""
        if self.target_addr < 0:
            raise ValueError("callee callsite census target must be nonnegative")
        if any(fact.evidence_target_addr < 0 for fact in iter(self.facts)):
            raise ValueError("callee callsite fact target must be nonnegative")
        callsite_keys = tuple(
            (id(fact.evidence_project), fact.callsite_addr) for fact in iter(self.facts)
        )
        if operator.ne(len(set(callsite_keys)), len(callsite_keys)):
            raise ValueError("callee callsite census contains duplicate facts")
        normalized = sum(fact.summary is not None for fact in iter(self.facts))
        if (
            operator.ne(self.raw_fact_count, len(self.facts))
            or operator.ne(self.normalized_fact_count, normalized)
            or operator.ne(self.failure_count, self.raw_fact_count - normalized)
        ):
            raise ValueError("callee callsite census accounting does not close")


class _CalleeCallsiteCensusOwner8616(Protocol):
    """Owned census registry carried by a dynamic third-party project."""

    _inertia_callee_callsite_census_8616: object
@cython.ccall
def callee_callsite_censuses_by_addr_8616(
    project: object,
) -> object:
    """Return the authoritative validated per-project census registry."""
    census: object
    target_addr: object
    owner = cast(_CalleeCallsiteCensusOwner8616, project)
    try:
        registry = owner._inertia_callee_callsite_census_8616
    except AttributeError:
        registry = {}
        owner._inertia_callee_callsite_census_8616 = registry
    if not isinstance(registry, dict):
        raise TypeError("callee callsite census registry must be a dict")
    for target_addr, census in registry.items():
        if not isinstance(target_addr, int) or isinstance(target_addr, bool):
            raise TypeError("callee callsite census keys must be integers")
        if not isinstance(census, CalleeCallsiteCensus8616):
            raise TypeError("callee callsite census registry has a wrong value type")
        if operator.ne(census.target_addr, target_addr):
            raise ValueError("callee callsite census key disagrees with target")
        census.validate()
    return registry


@cython.ccall
def attach_callee_callsite_censuses_8616(
    project: object,
    censuses: object,
) -> None:
    """Attach an already-derived complete census registry atomically."""
    temporary = cast(_CalleeCallsiteCensusOwner8616, SimpleNamespace())
    temporary._inertia_callee_callsite_census_8616 = dict(censuses)
    validated = callee_callsite_censuses_by_addr_8616(temporary)
    cast(
        _CalleeCallsiteCensusOwner8616,
        project,
    )._inertia_callee_callsite_census_8616 = dict(validated)


@cython.ccall
def record_callee_callsite_census_8616(
    project: object,
    census: CalleeCallsiteCensus8616,
) -> None:
    """Record one validated census without discarding existing targets."""
    census.validate()
    registry = dict(callee_callsite_censuses_by_addr_8616(project))
    registry[census.target_addr] = census
    cast(
        _CalleeCallsiteCensusOwner8616,
        project,
    )._inertia_callee_callsite_census_8616 = registry
