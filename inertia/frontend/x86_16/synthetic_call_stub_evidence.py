"""Transport exact synthetic call-stub addresses from frontend image builders.

Layer: Frontend.
Responsibility: identify analysis-only callee stubs whose placeholder bodies
cannot by themselves prove register preservation or return semantics. Their
exact identity may be combined with a separately registered calling-convention
contract by the Semantics owner.
Forbidden: inferring stubs from function names, rendered code, or call shape.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

__all__ = (
    "SyntheticCallStubRegistry8616",
    "is_synthetic_call_stub_8616",
    "record_synthetic_call_stubs_8616",
    "synthetic_call_stub_registry_8616",
)


@dataclass(frozen=True, slots=True)
class SyntheticCallStubRegistry8616:
    """Exact analysis-only targets plus a closed frontend evidence census."""

    addresses: frozenset[int]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closes_evidence(self) -> bool:
        """Return whether every supplied address was classified exactly once."""
        return (
            self.raw_fact_count == self.normalized_fact_count == len(self.addresses)
            and self.classified_fact_count == self.materialized_count == len(self.addresses)
            and self.failure_count == 0
        )


class _SyntheticCallStubOwner8616(Protocol):
    """Owned project field carrying synthetic call-stub evidence."""

    _inertia_synthetic_call_stub_registry_8616: SyntheticCallStubRegistry8616


def synthetic_call_stub_registry_8616(owner: object) -> SyntheticCallStubRegistry8616 | None:
    """Read the typed synthetic-stub registry from a project boundary."""
    try:
        registry = cast(_SyntheticCallStubOwner8616, owner)._inertia_synthetic_call_stub_registry_8616
    except AttributeError:
        return None
    return registry if isinstance(registry, SyntheticCallStubRegistry8616) else None


def record_synthetic_call_stubs_8616(
    owner: object,
    addresses: frozenset[int],
) -> SyntheticCallStubRegistry8616:
    """Publish exact frontend-provided synthetic call-stub addresses."""
    normalized = frozenset(
        address
        for address in addresses
        if isinstance(address, int) and not isinstance(address, bool) and address >= 0
    )
    existing = synthetic_call_stub_registry_8616(owner)
    merged = normalized | (existing.addresses if existing is not None else frozenset())
    failure_count = len(addresses) - len(normalized)
    registry = SyntheticCallStubRegistry8616(
        addresses=merged,
        raw_fact_count=len(merged) + failure_count,
        normalized_fact_count=len(merged),
        classified_fact_count=len(merged),
        materialized_count=len(merged),
        failure_count=failure_count,
    )
    cast(_SyntheticCallStubOwner8616, owner)._inertia_synthetic_call_stub_registry_8616 = registry
    return registry


def is_synthetic_call_stub_8616(owner: object, address: int) -> bool:
    """Return whether frontend evidence marks ``address`` as analysis-only."""
    registry = synthetic_call_stub_registry_8616(owner)
    return registry is not None and registry.closes_evidence and address in registry.addresses
