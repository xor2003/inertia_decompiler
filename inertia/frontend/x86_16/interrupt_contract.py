# cython: language_level=3, infer_types=True
"""Shared address contract for lifted x86-16 software interrupts.

Layer: Frontend contract.
Responsibility: assign disjoint synthetic address ranges to raw interrupt
vectors, DOS services, and non-DOS interrupt helpers. No semantic recovery or
C rendering belongs here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from typing import Protocol, cast
import dataclasses
import operator
import builtins

INTERRUPT_CORE_VECTOR_BASE: cython.longlong = 0xFF000
INTERRUPT_CORE_VECTOR_COUNT: cython.longlong = 0x100
INTERRUPT_SERVICE_BASE_ADDR: cython.longlong = 0xFD000
DOS_SERVICE_BASE_ADDR: cython.longlong = 0xFE000

__all__ = [
    "DOS_SERVICE_BASE_ADDR",
    "INTERRUPT_CORE_VECTOR_BASE",
    "INTERRUPT_CORE_VECTOR_COUNT",
    "INTERRUPT_SERVICE_BASE_ADDR",
    "SoftwareInterruptServiceTargetFact8616",
    "SoftwareInterruptServiceTargetRegistry8616",
    "interrupt_core_addr_8616",
    "interrupt_vector_from_core_addr_8616",
    "record_software_interrupt_service_target_8616",
    "software_interrupt_service_fact_8616",
    "software_interrupt_service_target_8616",
]


@dataclasses.dataclass(frozen=True, )
class SoftwareInterruptServiceTargetFact8616:
    """Exact frontend mapping from one interrupt instruction to its service."""

    function_addr: cython.longlong
    callsite_addr: cython.longlong
    vector: cython.longlong
    target_addr: cython.longlong
    helper_name: object


@dataclasses.dataclass(frozen=True, )
class SoftwareInterruptServiceTargetRegistry8616:
    """Immutable project registry of exact interrupt service targets."""

    facts: object
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong

    @property
    def closes_evidence(self) -> cython.bint:
        """Return whether every retained mapping has a closed evidence loop."""
        count = len(self.facts)
        return (
            self.raw_fact_count == self.normalized_fact_count == count
            and self.classified_fact_count == self.materialized_count == count
            and self.failure_count == 0
        )


class _SoftwareInterruptServiceTargetOwner8616(Protocol):
    """Owned project field carrying interrupt service target evidence."""

    _inertia_software_interrupt_service_targets_8616: SoftwareInterruptServiceTargetRegistry8616


@cython.ccall
def _software_interrupt_service_target_registry_8616(
    owner: object,
) -> SoftwareInterruptServiceTargetRegistry8616 | None:
    """Read the typed service-target registry from a project boundary."""
    try:
        registry = cast(
            _SoftwareInterruptServiceTargetOwner8616,
            owner,
        )._inertia_software_interrupt_service_targets_8616
    except AttributeError:
        return None
    return registry if isinstance(registry, SoftwareInterruptServiceTargetRegistry8616) else None


def record_software_interrupt_service_target_8616(
    owner: object,
    fact: SoftwareInterruptServiceTargetFact8616,
) -> SoftwareInterruptServiceTargetRegistry8616:
    """Publish one exact frontend service target, rejecting contradictions."""
    existing: object
    previous: object
    existing = _software_interrupt_service_target_registry_8616(owner)
    facts_by_key = {
        (item.function_addr, item.callsite_addr): item
        for item in iter((existing.facts if existing is not None else ()))
    }
    key = (fact.function_addr, fact.callsite_addr)
    previous = facts_by_key.get(key)
    if previous is not None and operator.ne(previous, fact):
        raise ValueError("interrupt callsite has contradictory service target evidence")
    facts_by_key[key] = fact
    facts = tuple(facts_by_key[item] for item in builtins.iter(sorted(facts_by_key)))
    count = len(facts)
    registry = SoftwareInterruptServiceTargetRegistry8616(
        facts,
        count,
        count,
        count,
        count,
        0,
    )
    cast(
        _SoftwareInterruptServiceTargetOwner8616,
        owner,
    )._inertia_software_interrupt_service_targets_8616 = registry
    return registry


@cython.ccall
def software_interrupt_service_target_8616(
    owner: object,
    *,
    function_addr: cython.longlong,
    callsite_addr: cython.longlong,
    vector: cython.longlong,
) -> int | None:
    """Return one exact service target only from a closed frontend registry."""
    fact: object
    fact = software_interrupt_service_fact_8616(
        owner,
        function_addr=function_addr,
        callsite_addr=callsite_addr,
        vector=vector,
    )
    return None if fact is None else fact.target_addr


def software_interrupt_service_fact_8616(
    owner: object,
    *,
    function_addr: cython.longlong,
    callsite_addr: cython.longlong,
    vector: cython.longlong,
) -> SoftwareInterruptServiceTargetFact8616 | None:
    """Return one exact service identity from a closed frontend registry."""
    registry: object
    registry = _software_interrupt_service_target_registry_8616(owner)
    if registry is None or not registry.closes_evidence:
        return None
    matches = tuple(
        fact
        for fact in iter(registry.facts)
        if operator.eq(fact.function_addr, function_addr)
        and operator.eq(fact.callsite_addr, callsite_addr)
        and operator.eq(fact.vector, vector)
    )
    return matches[0] if len(matches) == 1 else None


@cython.ccall
def interrupt_core_addr_8616(vector: cython.longlong) -> cython.longlong:
    """Return the raw lifted-call target for one interrupt vector."""
    if not 0 <= vector < INTERRUPT_CORE_VECTOR_COUNT:
        raise ValueError(f"interrupt vector out of range: {vector}")
    return INTERRUPT_CORE_VECTOR_BASE + vector


@cython.ccall
def interrupt_vector_from_core_addr_8616(target_addr: cython.longlong) -> int | None:
    """Decode an exact interrupt vector from a raw lifted-call target."""
    vector = target_addr - INTERRUPT_CORE_VECTOR_BASE
    return vector if 0 <= vector < INTERRUPT_CORE_VECTOR_COUNT else None
