"""Shared address contract for lifted x86-16 software interrupts.

Layer: Frontend contract.
Responsibility: assign disjoint synthetic address ranges to raw interrupt
vectors, DOS services, and non-DOS interrupt helpers. No semantic recovery or
C rendering belongs here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

INTERRUPT_CORE_VECTOR_BASE: int = 0xFF000
INTERRUPT_CORE_VECTOR_COUNT: int = 0x100
INTERRUPT_SERVICE_BASE_ADDR: int = 0xFD000
DOS_SERVICE_BASE_ADDR: int = 0xFE000

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


@dataclass(frozen=True, slots=True)
class SoftwareInterruptServiceTargetFact8616:
    """Exact frontend mapping from one interrupt instruction to its service."""

    function_addr: int
    callsite_addr: int
    vector: int
    target_addr: int
    helper_name: str


@dataclass(frozen=True, slots=True)
class SoftwareInterruptServiceTargetRegistry8616:
    """Immutable project registry of exact interrupt service targets."""

    facts: tuple[SoftwareInterruptServiceTargetFact8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closes_evidence(self) -> bool:
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
    existing = _software_interrupt_service_target_registry_8616(owner)
    facts_by_key = {
        (item.function_addr, item.callsite_addr): item
        for item in (existing.facts if existing is not None else ())
    }
    key = (fact.function_addr, fact.callsite_addr)
    previous = facts_by_key.get(key)
    if previous is not None and previous != fact:
        raise ValueError("interrupt callsite has contradictory service target evidence")
    facts_by_key[key] = fact
    facts = tuple(facts_by_key[item] for item in sorted(facts_by_key))
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


def software_interrupt_service_target_8616(
    owner: object,
    *,
    function_addr: int,
    callsite_addr: int,
    vector: int,
) -> int | None:
    """Return one exact service target only from a closed frontend registry."""
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
    function_addr: int,
    callsite_addr: int,
    vector: int,
) -> SoftwareInterruptServiceTargetFact8616 | None:
    """Return one exact service identity from a closed frontend registry."""
    registry = _software_interrupt_service_target_registry_8616(owner)
    if registry is None or not registry.closes_evidence:
        return None
    matches = tuple(
        fact
        for fact in registry.facts
        if fact.function_addr == function_addr
        and fact.callsite_addr == callsite_addr
        and fact.vector == vector
    )
    return matches[0] if len(matches) == 1 else None


def interrupt_core_addr_8616(vector: int) -> int:
    """Return the raw lifted-call target for one interrupt vector."""
    if not 0 <= vector < INTERRUPT_CORE_VECTOR_COUNT:
        raise ValueError(f"interrupt vector out of range: {vector}")
    return INTERRUPT_CORE_VECTOR_BASE + vector


def interrupt_vector_from_core_addr_8616(target_addr: int) -> int | None:
    """Decode an exact interrupt vector from a raw lifted-call target."""
    vector = target_addr - INTERRUPT_CORE_VECTOR_BASE
    return vector if 0 <= vector < INTERRUPT_CORE_VECTOR_COUNT else None
